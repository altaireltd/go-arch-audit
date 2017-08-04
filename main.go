package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os/exec"
	"strings"

	"github.com/ginabythebay/alpm"
)

type avg struct {
	Name       string      `json:"name"`
	Packages   []string    `json:"packages"`
	Status     string      `json:"status"`
	Severity   string      `json:"severity"`
	Type       string      `json:"type"`
	Affected   string      `json:"affected"`
	Fixed      interface{} `json:"fixed"`
	Ticket     interface{} `json:"ticket"`
	Issues     []string    `json:"issues"`
	Advisories []string    `json:"advisories"`
}

func pkgvers() (ret map[string]string) {
	ret = make(map[string]string)
	out, err := exec.Command("pacman", "-Q").Output()
	if err != nil {
		log.Fatal(err)
	}
	for _, line := range strings.Split(strings.Trim(string(out), "\n"), "\n") {
		words := strings.Split(line, " ")
		ret[words[0]] = words[1]
	}
	return ret
}

func main() {
	res, err := http.Get("https://security.archlinux.org/issues/all.json")
	if err != nil {
		log.Fatal(err)
	}
	data, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Fatal(err)
	}
	array := new([]avg)
	json.Unmarshal(data, array)
	pkgvers := pkgvers()
	for _, avg := range *array {
		ver, ok := pkgvers[avg.Packages[0]]
		if !ok || alpm.VerCmp(ver, avg.Affected) < 0 {
			continue
		}
		if fixed, ok := avg.Fixed.(string); ok {
			if alpm.VerCmp(ver, fixed) > 0 {
				continue
			}
			fmt.Printf("Package %s is affected by [%s]. %s risk! Update to %s!\n",
				avg.Packages[0],
				strings.Join(avg.Issues, ", "),
				avg.Severity,
				fixed)
		} else {
			fmt.Printf("Package %s is affected by [%s]. %s risk!\n",
				avg.Packages[0],
				strings.Join(avg.Issues, ", "),
				avg.Severity)
		}
	}
}
