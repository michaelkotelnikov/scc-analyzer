package main

import (
	"flag"
	"io"
	"log"
	"os"

	"scc-analyzer/pkg/analyzer"
	"scc-analyzer/pkg/kube"

	"github.com/olekukonko/tablewriter"
)

func cmdUsage() {
	message := "Usage: " + os.Args[0] + " [OPTIONS] argument ...\n"

	_, err := io.WriteString(os.Stdout, message)
	if err != nil {
		log.Fatalf("Error: %v", err)

		return
	}

	flag.PrintDefaults()
}

func main() {
	flag.Usage = cmdUsage

	namespace := flag.String(
		"namespace",
		"default",
		"Specify the Namespace to run the analyzer on.",
	)

	expand := flag.Bool(
		"expand",
		false,
		"Use flag to viauslize SCC rule description",
	)

	flag.Parse()

	context := ""

	var rules *analyzer.Rules

	client, err := kube.NewClient(context)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	perms, err := analyzer.BuildPermissions(client, *namespace)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	rows := [][]string{}
	table := tablewriter.NewWriter(os.Stdout)
	table.SetRowLine(true)
	table.SetAutoMergeCellsByColumnIndex([]int{0, 1})

	if *expand {
		rules = analyzer.BuildRules()

		table.SetHeader([]string{
			"Namespace",
			"Service Account",
			"Rule Description",
			"SCC",
		},
		)
	} else {
		table.SetHeader([]string{
			"Namespace",
			"Service Account",
			"SCC",
		},
		)
	}

	for _, sa := range perms.ServiceAccounts {
		saSCC := analyzer.CreateServiceAccountMap(perms, sa)
		for _, scc := range saSCC.SecurityContextConstraints {
			if *expand {
				evaluations := rules.EvaluateSCC(&scc)
				for _, evaluation := range evaluations {
					row := []string{*namespace, sa.Name, evaluation, scc.Name}
					rows = append(rows, row)
				}
			} else {
				row := []string{*namespace, sa.Name, scc.Name}
				rows = append(rows, row)
			}
		}
	}

	table.AppendBulk(rows)
	table.Render()
}
