package main

import (
	"context"
	"fmt"

	"github.com/0zuzu/pal2pal/utils"
)

type App struct {
	ctx context.Context
}

func NewApp() *App {
	return &App{}
}

// startup is called when the app starts.
func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	// Check if identity exists, if not create one
	_, err := utils.ReadIdentity()
	if err != nil {
		fmt.Println("No identity found, generating a new one...")
	}
}

// Greet returns a greeting for the given name
func (a *App) Greet(name string) string {
	return fmt.Sprintf("Hello %s, It's show time!", name)
}

func (a *App) shutdown(ctx context.Context) {
	// Perform any cleanup tasks here
}
