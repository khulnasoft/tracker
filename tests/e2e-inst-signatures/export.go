package main

import (
	"github.com/khulnasoft-lab/tracker/tests/e2e-inst-signatures/datasourcetest"
	"github.com/khulnasoft-lab/tracker/types/detect"
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
}

var ExportedDataSources = []detect.DataSource{
	datasourcetest.New(),
}