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
    def __init__(self, avoid=set()):
        # TODO: Can't get old options list? Can avoid regenerating CFGAccurate?
        l.debug('Generating CFG')
        # Need to use CFG accurate to get argument count analysis, or I have to
        # do it myself
        self._p = angr.Project(self.project.filename,
                               load_options={'auto_load_libs': False})
        self._cfg = self._p.analyses.CFGAccurate(keep_state=True)
        #self._p = angr.Project(self.project.filename,
        #                       load_options={'auto_load_libs': False})
        #self._cfg = self._p.analyses.CFG()
        l.debug('CFG Generated')

        # Fix functions to try summarizing
        self._avoid = avoid
        self._to_summarize = {addr: f for addr, f in self._cfg.functions.iteritems()
                              if self._is_summary_candidate(addr, f)}

        # Generate summaries
        self._fresh_counter = itertools.count()
        self._globals = None
        self._is_summarized = {}
        self._create_summaries()

    def _is_summary_candidate(self, addr, f):
        # Should patch for MIPS, see https://github.com/angr/fidget/blob/master/fidget/structures.py#L214

        # Skip user avoided functions
        if addr in self._avoid:
            l.debug('Function %s avoided', f.name)
            return False

        # Skip _start
        if addr == self._p.entry:
            l.debug('Skipping entry point')
            return False

        # Don't try to patch simprocedures
        if self._p.is_hooked(addr):
            l.debug('Skipping simprocedure %s',
                    self._p.hooked_by(addr).procedure.__name__)
            return False

        # Same as above
        if f.is_simprocedure:
            l.debug('Skipping simprocedure %s', f.name)
            return False

        # Don't touch functions not in any segment
        if self._p.loader.main_bin.find_segment_containing(addr) is None:
            l.debug('Skipping function %s not mapped', f.name)
            return False

        # Don't touch functions not in .text if it exists
        if '.text' in self._p.loader.main_bin.sections_map:
            sec = self._p.loader.main_bin.find_section_containing(addr)
            if sec is None or sec.name != '.text':
                l.debug('Skipping function %s not in .text', f.name)
                return False

        # Don't patch PLT functions
        if addr in self._p.loader.main_bin.plt.values():
            l.debug('Skipping function %s in PLT', f.name)
            return False

        # Skip unresolved indirect jumps that CFG couldn't parse
        if f.has_unresolved_jumps:
            l.debug('Skipping function %s with unresolved jumps', f.name)
            return False

        # Check if function starts at a SimProcedure (edge case)
        if self._cfg.get_any_node(addr).simprocedure_name is not None:
            l.debug('Skipping function %s starting with a SimProcedure', f.name)
            return False

        # Nice!
        return True

    def _create_summaries(self):
        cg = self._p.kb.callgraph
        work_cg = {addr: set(cg[addr].keys()) for addr in cg \
                   if addr in self._to_summarize \
                      and all(map(lambda addr: addr in self._to_summarize, cg[addr]))}

        while True:
            good = set()
            bad = set()
            for addr in work_cg:
                if len(work_cg[addr]) != 0: pass
                if self._try_summarize(self._to_summarize[addr]):
                    for addr2 in work_cg:
                        work_cg[addr2].discard(addr)
                    good.add(addr)
                else:
                    bad.add(addr)

            if len(good) == 0: break
            work_cg = {addr: calls for addr, calls in work_cg.iteritems() \
                       if addr not in good | bad and \
                          len(bad.intersection(calls)) == 0}

    def _try_summarize(self, f):
        l.debug('Attempting to hook: %s', f.name)

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
        self._is_summarized[f.addr] = angr.Hook(FHook)

        self._p.hook(f.addr, self._is_summarized[f.addr])
        return True

    def _has_cycle(self, f):
        try:
            next(nx.simple_cycles(f.graph))
            return True
        except StopIteration:
            return False

    def _has_side_effect(self, f):
        # TODO: Assumes any write to outside the base of the stack frame is a
        #       side effect, and everything else is not
        #       Not sure if address concretization messes with this

        for b in f.blocks:
            # Technically I don't need this?
            for stmt in b.vex.statements:
                if isinstance(stmt, pyvex.stmt.Dirty):
                    return True
            if b.vex.jumpkind == 'Ijk_Call' and isinstance(b.vex.next, pyvex.expr.Const) \
               and b.vex.next.con.value in self._is_summarized:
                continue
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
        stack_lim = self._p.arch.initial_sp - self._p.arch.stack_size \
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

    def _fresh_name(self):
        return '__tmpvar__%d' % next(self._fresh_counter)

    def _abstract_globals(self, state):
        if self._globals is None:
            self._globals = {}
            secs = filter(lambda s: s.is_readable and (s.name == '.data' or s.name == '.bss'),
                          self._p.loader.main_bin.sections)
            for s in secs:
                self._globals[s.min_addr] = claripy.BVS(self._fresh_name(),
                                                        s.memsize * 8)
        for addr, var in self._globals.iteritems():
            state.memory.store(addr, var)

    def _generate_hook(self, f):
        # TODO: Check types of args?
        # It seems to count one more than actual number of args on x64?
        num_args = f.num_arguments - 1

        # TODO: hardcoded size
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
            rs = self.state.se._solver
            for o, n in zip(sym_args, actual_args):
                if isinstance(n, simuvex.SimActionObject):
                    n = n.to_claripy()
                rs.add_replacement(o, n)

            for addr, sym in fglobals.iteritems():
                rs.add_replacement(sym, self.state.memory.load(addr, sym.size()/8))

            rep_val = rs._replacement(rval)
            # TODO: Should be remove_replacements, update once they fix that function
            rs.clear_replacements()
            l.debug('Hook %s(%s): %s', hook_name, actual_args, rep_val)
            return rep_val

        FHook = type(hook_name, (simuvex.SimProcedure,), {'__init__': __init__,
                                                          'run': run,
                                                          'rval': rval})
        return FHook

    def _get_symbolic_rval(self, f, *sym_args):
        # TODO: handle floats properly?
        # TODO: need to check if all paths return, not just some paths
        cc = f.calling_convention if f.calling_convention is not None \
                                  else simuvex.DefaultCC[self._p.arch.name](self._p.arch)
        deadend_addr = self._p._simos.return_deadend
        state = self._p.factory.call_state(f.addr, *sym_args,
                                           cc=cc,
                                           base_state=None,
                                           ret_addr = deadend_addr,
                                           add_options={simuvex.o.REPLACEMENT_SOLVER},
                                           toc=None)
        self._abstract_globals(state)

        caller = self._p.factory.path_group(state, immutable=True)
        caller_end_unpruned = caller.step(until=lambda pg: len(pg.active) == 0) \
                                    .unstash(from_stash='deadended')
        caller_end_unmerged = caller_end_unpruned.prune(
                                filter_func=lambda pt: pt.addr == deadend_addr)
        if len(caller_end_unmerged.active) == 0:
            return None
        rstate = caller_end_unmerged.merge().active[0].state
        rval = rstate.simplify(cc.get_return_val(rstate,
                                                 stack_base=rstate.regs.sp - \
                                                 cc.STACKARG_SP_DIFF))
        return rval
    
    def hook_all(self):
        for addr, hk in self._is_summarized.iteritems():
            self.project.hook(addr, hk)

    def hook_some(self, addrs):
        for addr in addrs:
            self.project.hook(addr, self._is_summarized[addr])

    def get_summaries(self):
        return self._is_summarized

register_analysis(Summarizer, 'Summarizer')
