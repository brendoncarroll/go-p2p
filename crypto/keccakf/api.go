package keccakf

type State1600 = [25]uint64

// Permute1600 applies KeccakF1600 to x inplace.
func Permute1600(x *State1600) {
	keccakF1600(x)
}
