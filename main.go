package main

import (
	"syscall/js"
)

func sayHello(this js.Value, args []js.Value) interface{} {
	message := "Hello from Go WebAssembly!"
	js.Global().Get("document").Call("getElementById", "output").Set("innerText", message)
	return nil
}

func main() {
	js.Global().Set("sayHello", js.FuncOf(sayHello))
	select {}
}
