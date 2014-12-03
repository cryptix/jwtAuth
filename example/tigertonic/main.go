package main

import (
	"os"

	"github.com/codegangsta/cli"
)

func main() {
	app := cli.NewApp()
	app.Name = "jwtAuth tigertonic example"

	app.Commands = []cli.Command{
		{
			Name:      "serve",
			ShortName: "s",
			Action:    serveCmd,
		},
		{
			Name:      "toggle",
			ShortName: "t",
			Action:    toggleCmd,
		},
	}

	app.Run(os.Args)
}
