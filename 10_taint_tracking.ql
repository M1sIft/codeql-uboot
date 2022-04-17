/**
 * @kind path-problem
 */

import cpp
import semmle.code.cpp.dataflow.TaintTracking
import DataFlow::PathGraph

// class NetworkByteSwap extends Expr {
//   // TODO: copy from previous step
// }

class Config extends TaintTracking::Configuration {
  Config() { this = "NetworkToMemFuncLength" }

  override predicate isSource(DataFlow::Node source) {
    exists(MacroInvocation m | m.getMacroName().regexpMatch("ntoh(l|s|ll)") | source.asExpr() = m.getExpr() )
  }
  override predicate isSink(DataFlow::Node sink) {
    exists(FunctionCall c | c.getTarget().getName() = "memcpy" |sink.asExpr() = c.getArgument(2)) 
  }
}

from Config cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink, source, sink, "Network byte swap flows to memcpy"