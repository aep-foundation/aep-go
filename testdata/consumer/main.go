package main

import (
	"fmt"

	aep "github.com/aep-foundation/aep-go"
	_ "github.com/aep-foundation/aep-go/agent"
	_ "github.com/aep-foundation/aep-go/platform"
	_ "github.com/aep-foundation/aep-go/service"
)

func main() {
	fmt.Println(aep.Version)
}
