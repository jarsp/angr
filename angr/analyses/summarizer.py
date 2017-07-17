import angr
import simuvex
import claripy
import logging
import pyvex
import networkx as nx
import itertools

from ..analysis import Analysis, register_analysis

l = logging.getLogger('angr.analyses.summarizer')
l.setLevel('DEBUG')

class Summarizer(Analysis):
    """
    Attempt to create function summaries.
    """

    _bad_fns = {'_init', '__stack_chk_fail', '__libc_start_main', 'sub_400440',
                '_start', 'deregister_tm_clones', '__do_global_dtors_aux', 'frame_dummy',
                '__libc_csu_init'}

    def __init__(self, avoid=set()):
        # TODO: Can't get old options list? Can avoid regenerating CFGAccurate?
        l.debug('Generating CFGAccurate')
        self._p = angr.Project(self.project.filename,
                               load_options={'auto_load_libs': False})
        self._cfg = self._p.analyses.CFGAccurate(keep_state=True)
        l.debug('CFG Generated')

        # Fix functions to try summarizing
        self._avoid = avoid
        self._to_summarize = {addr: f for addr, f in self._cfg.functions.iteritems()
                              if _is_summary_candidate(addr, f)}

        # Generate summaries
        self._fresh_counter = itertools.count()
        self._globals = {}
        self._is_summarized = {}
        self._create_summaries()

    def _is_summary_candidate(self, addr, f):
        return addr not in self.avoid and not f.is_simprocedure \
                and f.name not in self._bad_fns

    def _create_summaries(self):
        cg = self._p.kb.callgraph
        work_cg = {addr: set(cg[addr].keys()) for addr in cg \
                   if all(map(lambda addr: addr in self._to_summarize, cg[addr]))}

        while True:
            good = set()
            bad = set()
            for addr in work_cg:
                if len(work_cg[addr]) != 0: pass
                if self._try_summarize(self._to_summarize[addr]):
                    for addr in work_cg:
                        work_cg[addr].discard(addr)
                    good.add(addr)
                else:
                    bad.add(addr)

            if len(good) == 0: break
            work_cg = {addr: calls for addr, calls in work_cg.iteritems() \
                       if addr not in good and \
                          len(bad.intersection(calls)) == 0}

    def _try_summarize(f):
        l.debug('Attempting to hook: %s', f.name)
        self._track_global_reads(f)

        if self._has_cycle(f):
            l.debug('Failed to hook: %s has cycles, skipping', f.name)
            return False

        if self._has_side_effect(f):
            l.debug('Failed to hook: %s has side effects, skipping', f.name)
            return False

        FHook = self._generate_hook(f)
        if FHook is None:
            l.debug('Failed to generate hook: %s', f.name)
            return False

        l.debug('Hook generated for: %s', f.name)
        self._is_summarized[f.addr] = f

        self._p.hook(f.addr, angr.Hook(FHook))
        return True

    def _has_cycle(f):
        try:
            next(nx.simple_cycles(f.graph))
            return True
        except StopIteration:
            return False

    def _has_side_effect(f):
        # the following may no longer be necessary
        for b in f.blocks:
            if b.vex.jumpkind not in ['Ijk_Boring', 'Ijk_Ret']:
                return True

        cc = f.calling_convention if f.calling_convention is not None \
                                  else simuvex.DefaultCC[self._p.arch.name](self._p.arch)
        deadend_addr = self._p._simos.return_deadend
        num_args = f.num_arguments - 1
        args = [claripy.BVS(self._fresh_name(), 64) for _ in range(num_args)]
        state = self._p.factory.call_state(f.addr, *args,
                                           cc=cc,
                                           base_state=None,
                                           ret_addr=deadend_addr,
                                           add_options={simuvex.o.REPLACEMENT_SOLVER},
                                           toc=None)
        self._abstract_globals(state)

        base_sp = state.regs.sp
        stack_grows_to_zero = self._p.arch.stack_change < 0
        stack_lim = self._p.arch.initial_sp - self._P.arch.stack_size \
                    if stack_grows_to_zero \
                    else self._p.arch.initial_sp + self._p.arch.stack_size

        class BPCallback:
            def __init__(self):
                self.has_effect = False

            def check_side_effect(self, s):
                if self.has_effect: return

                write_addr = s.inspect.mem_write_address
                if stack_grows_to_zero:
                    cond = (claripy.Or(write_addr > base_sp, write_addr <= stack_lim), )
                else:
                    cond = (claripy.Or(write_addr < base_sp, write_addr >= stack_lim), )
                #l.debug(cond)
                self.has_effect = s.se.satisfiable(extra_constraints=cond)

        callback = BPCallback()
        state.inspect.b('mem_write', when=simuvex.BP_BEFORE,
                        action=callback.check_side_effect)

        caller = self._p.factory.path_group(state)
        caller.step(until=lambda pg: callback.has_effect or len(pg.active) == 0)

        return callback.has_effect

    def _fresh_name():
        return '__tmpvar__%d' % next(_fresh_counter)

    def _track_global_reads(f):
        reads = {}
        for b in f.blocks:
            for exp in b.vex.expressions:
                if exp.tag == 'Iex_Load' and exp.addr.tag == 'Iex_Const':
                    addr = exp.addr.con.value
                    sz = simuvex.engines.vex.size_bits(exp.ty)
                    if addr not in reads or sz > reads[addr]:
                        reads[addr] = sz

        # TODO: LLSC, CAS, LOADG, etc.
        for read_addr, sz in reads.iteritems():
            symvar = claripy.BVS(self._fresh_name(), sz)
            self._globals[read_addr] = symvar

    def _abstract_globals(state):
        for addr, var in self._globals.iteritems():
            state.memory.store(addr, var)

    def _generate_hook(f):
        num_args = f.num_arguments - 1
        sym_args = [claripy.BVS(self._fresh_name(), 64)
                    for _ in range(num_args)]
        hook_name = '__hook_%s' % f.name
        rval = self._get_symbolic_rval(f, *sym_args)
        if rval is None: return None
        fglobals = self._globals

        def __init__(self, *args, **kwargs):
            kwargs['num_args'] = num_args
            simuvex.SimProcedure.__init__(self, *args, **kwargs)

        def run(self, *actual_args):
            rs = self.state.se._solve
            for o, n in zip(sym_args, actual_args):
                if isinstance(n, simuvex.SimActionObject):
                    n = n.to_claripy()
                rs.add_replacement(o, n)

            for addr, sym in fglobals.iteritems():
                rs.add_replacement(sym, self.state.memory.load(addr, sym.size()/8))

            rep_val = rs._replacement(rval)
            rs.clear_replacements()
            return rep_val

        FHook = type(hook_name, (simuvex.SimProcedure,), {'__init__': __init__,
                                                          'run': run})
        return FHook

    def _get_symbolic_rval(f, *sym_args):
        cc = f.calling_convention if f.calling_convention is not None \
                                  else simuvex.DefaultCC[self._p.arch.name](self._p.arch)
        deadend_addr = self._p._simos.return_deadend
        state = self._p.factory.call_state(f.addr, *args,
                                           cc=cc,
                                           base_state=None,
                                           ret_addr = deadend_addr,
                                           add_options={simuvex.o.REPLACEMENT_SOLVER},
                                           toc=None)
        self._abstract_globals(state)

        caller = self._p.factory.path_group(state, immutable=True)
        caller_end_unpruned = caller.step(until=lambda pg: len(pg.active) == 0) \
                                    .unstash(from_stash='deadended')
        caller_end_unmerged = called_end_unpruned.prune(
                                filter_func=lambda pt: pt.addr == deadend_addr)
        if len(caller_end_unmerged.active) == 0:
            return None
        rstate = caller_end_unmerged.merge().active[0].state
        rval = rstate.simplify(cc.get_return_value(rstate,
                                                   stack_base=rstate.regs.sp - \
                                                   cc.STACKARG_SP_DIFF)
        return rval

register_analysis(Summarizer, 'Summarizer')
