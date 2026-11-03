pragma circom 2.1.6;

// Test fixture: a single constraint, a === 1. Used to check that a witness
// violating a constraint is rejected before proving (see check_witness).
template AssertOne() {
    signal input a;
    signal output b;
    a === 1;
    b <== a * a;
}

component main = AssertOne();
