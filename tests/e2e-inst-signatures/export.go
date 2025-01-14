package main

import (
	"github.com/khulnasof/tracker/types/detect"
	"github.com/khulnasoft/tracker/tests/e2e-inst-signatures/datasourcetest"
)

var ExportedSignatures = []detect.Signature{
	// Instrumentation e2e signatures
	&e2eProcessExecuteFailed{},
	&e2eVfsWrite{},
	&e2eVfsWritev{},
	&e2eFileModification{},
	&e2eSecurityInodeRename{},
	&e2eContainersDataSource{},
	&e2eBpfAttach{},
	&e2eProcessTreeDataSource{},
	&e2eHookedSyscall{},
	&e2eSignatureDerivation{},
	&e2eDnsDataSource{},
	&e2eWritableDatasourceSig{},
	&e2eSecurityPathNotify{},
	&e2eSetFsPwd{},
	&e2eFtraceHook{},
	&e2eSuspiciousSyscallSource{},
}

var ExportedDataSources = []detect.DataSource{
	datasourcetest.New(),
}
