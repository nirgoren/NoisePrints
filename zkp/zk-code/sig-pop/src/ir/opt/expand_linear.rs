//! replace PfLinear with PfAdd and PfMulls

use crate::ir::term::*;
use crate::ir::opt::visit::RewritePass;
use crate::ir::term::ty;
use std::cmp::max;

struct Pass;


impl RewritePass for Pass {
    fn visit<F: Fn() -> Vec<Term>>(&mut self, _: &mut Computation, t: &Term, get: F) -> Option<Term> {
        match t.op() {
            Op::PfLinear(n,m) => {
                let children = get();
                let mut terms = Vec::with_capacity(*n);
                // not the most efficient way to do this but here we are
                let mut getter_terms: Vec<Term> = Vec::new();
                let (getter, output_op): (Box<dyn Fn(usize,Term) -> Term>, Op) = match ty::check(&children[0]) {
                    Sort::Tuple(_) => (Box::new(|i, val| term![Op::Field(i); val]), Op::Tuple),
                    Sort::Array(ks, vs, _) => {
                        let (output_k, output_v, _) = vs.as_array();
                        getter_terms = ks.elems_iter().take(max(*n, *m)).collect();
                        (Box::new(|i, val| term![Op::Select; val, getter_terms[i].clone()]), Op::Array(output_k.clone(), output_v.clone()))
                    }
                    _ => unimplemented!()
                };
                for i in 0..*n {
                    let mut term = term![PF_MUL; getter(0, getter(i, children[0].clone())), getter(0, children[1].clone())];
                    for j in 1..*m {
                        term = term![PF_ADD; term![PF_MUL; getter(j, getter(i, children[0].clone())), getter(j, children[1].clone())], term];
                    }
                    terms.push(term);
                }
                Some(term(output_op, terms))
            },
            _ => None
        }
    }
}


pub fn expand_linear(c: &mut Computation) {
    Pass.traverse_full(c, true, true)
}
