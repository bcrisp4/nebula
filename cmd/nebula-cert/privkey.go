package main

import (
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"github.com/slackhq/nebula/cert"
)

type privkeyFlags struct {
	set        *flag.FlagSet
	outKeyPath *string
}

func newprivkeyFlags() *privkeyFlags {
	cf := privkeyFlags{set: flag.NewFlagSet("privkey", flag.ContinueOnError)}
	cf.set.Usage = func() {}
	cf.outKeyPath = cf.set.String("out-key", "", "Path to write the private key to. Defaults to STDOUT.")
	return &cf
}

func privkey(args []string, out io.Writer, errOut io.Writer) error {
	cf := newprivkeyFlags()
	err := cf.set.Parse(args)
	if err != nil {
		return err
	}

	rawPriv := x25519Privkey()
  priv := cert.MarshalX25519PrivateKey(rawPriv)

  if *cf.outKeyPath == "" {
    fmt.Print(string(priv))
  } else {
	  err = ioutil.WriteFile(*cf.outKeyPath, priv, 0600)
	  if err != nil {
		  return fmt.Errorf("error while writing out-key: %s", err)
	  }
  }
	return nil
}

func privkeySummary() string {
	return "privkey <flags>: create a private key."
}

func privkeyHelp(out io.Writer) {
	cf := newprivkeyFlags()
	out.Write([]byte("Usage of " + os.Args[0] + " " + privkeySummary() + "\n"))
	cf.set.SetOutput(out)
	cf.set.PrintDefaults()
}
