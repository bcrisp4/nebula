package main

import (
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"github.com/slackhq/nebula/cert"
)

type pubkeyFlags struct {
	set        *flag.FlagSet
	inPrivPath *string
	outPubPath *string
}

func newpubkeyFlags() *pubkeyFlags {
	cf := pubkeyFlags{set: flag.NewFlagSet("pubkey", flag.ContinueOnError)}
	cf.set.Usage = func() {}
	cf.inPrivPath = cf.set.String("in-priv", "", "Path to read the private key to from. Defaults to STDIN.")
	cf.outPubPath = cf.set.String("out-pub", "", "Path to write the public key to. Defaults to STDOUT.")
	return &cf
}

func pubkey(args []string, out io.Writer, errOut io.Writer) error {
	cf := newpubkeyFlags()
	err := cf.set.Parse(args)
	if err != nil {
		return err
	}

  var rawPriv []byte
  var priv []byte
  if *cf.inPrivPath == "" {
    rawPriv, err = ioutil.ReadAll(os.Stdin)
    if err != nil {
      return fmt.Errorf("error while reading in-priv from STDIN", err)
    }
  } else {
      rawPriv, err = ioutil.ReadFile(*cf.inPrivPath)
      if err != nil {
        return fmt.Errorf("error while reading in-priv: %s", err)
      }
  }

  priv, _, err = cert.UnmarshalX25519PrivateKey(rawPriv)
  if err != nil {
    return fmt.Errorf("error while parsing in-priv: %s", err)
  }

  rawPub := x25519Pubkey(priv)
  pub := cert.MarshalX25519PublicKey(rawPub)

  if *cf.outPubPath == "" {
    fmt.Print(string(pub))
  } else {
	  err = ioutil.WriteFile(*cf.outPubPath, pub, 0600)
	  if err != nil {
		  return fmt.Errorf("error while writing out-pub: %s", err)
	  }
  }
	return nil
}

func pubkeySummary() string {
	return "pubkey <flags>: derive a public key from an existing private key."
}

func pubkeyHelp(out io.Writer) {
	cf := newpubkeyFlags()
	out.Write([]byte("Usage of " + os.Args[0] + " " + pubkeySummary() + "\n"))
	cf.set.SetOutput(out)
	cf.set.PrintDefaults()
}
