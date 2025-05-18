package main

import (
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/bhaiFi/security-monitor/internal/agentEngine"
	"github.com/bhaiFi/security-monitor/internal/logger"
	"golang.org/x/sys/windows"

	"github.com/kardianos/service"
)

func CheckAdmin() bool {

	_, err := os.Open("\\\\.\\PHYSICALDRIVE0")
	return err == nil
}

func RunElevated() {

	verb := "runas"
	exe, _ := os.Executable()
	cwd, _ := os.Getwd()
	args := strings.Join(os.Args[1:], " ")

	verbPtr, _ := syscall.UTF16PtrFromString(verb)
	exePtr, _ := syscall.UTF16PtrFromString(exe)
	cwdPtr, _ := syscall.UTF16PtrFromString(cwd)
	argsPtr, _ := syscall.UTF16PtrFromString(args)

	var showCmd int32 = 1

	err := windows.ShellExecute(0, verbPtr, exePtr, argsPtr, cwdPtr, showCmd)
	if err != nil {
		time.Sleep(2 * time.Second)
	}

	os.Exit(0)
}

// Define the service configuration.
func configureService() *service.Config {

	return &service.Config{
		Name:        "bhaifiAgent",
		DisplayName: "BhaiFi Agent",
		Description: "BhaiFi Agent",
		Option: service.KeyValue{
			service.StartType: service.ServiceStartAutomatic,
			service.OnFailure: service.OnFailureRestart,
		},
	}
}

// ------------------------------ Agent ------------------------------ //

var (
	systemLogger service.Logger
)

type program struct {
	AgentManager *agentEngine.AgentEngine
}

// ------------------------------ Operational ------------------------------ //

func (p *program) Start(s service.Service) error {

	go p.run()

	return nil
}

func (p *program) run() {

	logger.InitializeLogger(systemLogger)

	p.AgentManager = &agentEngine.AgentEngine{}

	p.AgentManager.Start()

}

func (p *program) Stop(s service.Service) error {
	if p.AgentManager != nil {
		go p.AgentManager.Stop()
	}
	return nil
}

// Driver function.
func main() {

	// Elevate the current process privilege to Admin if it is not already running with Admin privilege.
	if !CheckAdmin() {
		RunElevated()
	}

	prg := &program{}

	// Instantiate the service object.
	s, err := service.New(prg, configureService())
	if err != nil {
		systemLogger.Error(err)
		return
	}

	systemLogger, err = s.Logger(nil)
	if err != nil {
		systemLogger.Error(err)
	}

	// If the interactive flag is set, run the service in the shell (uncomment this to run in shell)
	// if *interactiveFlag || service.Interactive() {
	// 	systemLogger.Info("Running in interactive mode...")
	// 	prg.run() // Directly run the service logic
	// 	select {} // Keep the program running
	// 	return
	// }

	// if you want to run code in terminal then you have comment the code from line number 125-150
	_, err = s.Status()
	if err != nil {
		if err == service.ErrNotInstalled {
			err = s.Install()
			if err != nil {
				systemLogger.Error(err)
				return
			}
			systemLogger.Info("Infinity Agent Service installed.")
		} else {
			systemLogger.Error(err)
			return
		}
	}

	if service.Interactive() {
		err = s.Start()
		if err != nil {
			systemLogger.Error(err)
			return
		}
		systemLogger.Info("Infinity Agent Service has started.")
		return
	}

	// Run the service.
	err = s.Run()
	if err != nil {
		systemLogger.Error(err)
	}

}
