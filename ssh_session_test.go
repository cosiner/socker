package socker

import (
	"fmt"
	"testing"
)

func TestSessionPool(t *testing.T) {
	pool := newSessionPool(-1)
	defer pool.Close()

	token, _ := pool.Take()
	token.Release()
	fmt.Println(1)

	token, _ = pool.Take()
	defer token.Release()
	fmt.Println(2)

	token, _ = pool.Take()
	defer token.Release()
	fmt.Println(3)
}
