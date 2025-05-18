package logger

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/kardianos/service"
	"github.com/natefinch/lumberjack"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// ------------------------------ Global Access Object ------------------------------ //

var Logging *zap.Logger

// ------------------------------ Operations ------------------------------ //

func InitializeLogger(systemLogger service.Logger) {

	executablePath, err := os.Executable()
	if err != nil {
		LogFatal("init", "error getting the path of the executable", "", err)
		return
	}

	fmt.Println("executablePath", executablePath)
	logFilePath := filepath.Dir(executablePath)

	logDirectory := fmt.Sprintf("%s/.logs", logFilePath)
	info, err := ensureDirectory(logDirectory)
	if err != nil {
		err := fmt.Errorf("error creating log directory: %s", err.Error())
		systemLogger.Error(err)
		log.Fatal(err)
	}

	logPath := fmt.Sprintf("%s/log_%s.log", logDirectory, time.Now().Format("2006-01-02"))
	if info != nil {
		logPath = fmt.Sprintf("%s/log_%s.log", logDirectory, info.ModTime().Format("2006-01-02"))
	}

	if err := ensureLogFile(logPath); err != nil {
		err := fmt.Errorf("error creating log file: %s", err.Error())
		systemLogger.Error(err)
		log.Fatal(err)
	}

	encoderCfg := zap.NewProductionEncoderConfig()
	encoderCfg.EncodeTime = zapcore.ISO8601TimeEncoder
	core := zapcore.NewCore(
		zapcore.NewJSONEncoder(encoderCfg),
		zapcore.AddSync(&lumberjack.Logger{
			Filename:   logPath,
			MaxSize:    100, // MB
			MaxBackups: 3,
			MaxAge:     365, // Days
			Compress:   false,
			LocalTime:  true,
		}),
		zapcore.DebugLevel,
	)

	logger := zap.New(core, zap.AddCaller())
	defer logger.Sync()

	Logging = logger
}

func ensureDirectory(directoryPath string) (os.FileInfo, error) {

	info, err := os.Stat(directoryPath)

	if os.IsNotExist(err) {
		err = os.MkdirAll(directoryPath, os.ModePerm)
		if err != nil {
			return nil, err
		}
		info, err = os.Stat(directoryPath)
	}

	return info, err
}

func ensureLogFile(path string) error {

	_, err := os.Stat(path)

	if os.IsNotExist(err) {
		file, err := os.Create(path)
		if err != nil {
			return fmt.Errorf("failed to create log file: %v", err)
		}
		file.Close()
	}
	return nil
}

func LogDebug(source, activity, debugString string, object ...interface{}) {
	_, file, line, _ := runtime.Caller(1)
	caller := fmt.Sprintf("%s:%d", file, line)
	Logging.Debug("Debug",
		zap.String("Source", source),
		zap.Any("Object", object),
		zap.String("Activity", activity),
		zap.String("Caller", caller),
		zap.String("Debug", debugString),
	)
}

func LogError(source string, activity string, object interface{}, err error) {
	_, file, line, _ := runtime.Caller(1)
	caller := fmt.Sprintf("%s:%d", file, line)
	Logging.Error("Error",
		zap.String("Source", source),
		zap.Any("Object", object),
		zap.String("Activity", activity),
		zap.String("Caller", caller),
		zap.Error(err),
	)
}

func LogFatal(source string, activity string, object interface{}, err error) {
	_, file, line, _ := runtime.Caller(1)
	caller := fmt.Sprintf("%s:%d", file, line)
	Logging.Fatal("Fatal",
		zap.String("Source", source),
		zap.Any("Object", object),
		zap.String("Activity", activity),
		zap.String("Caller", caller),
		zap.Error(err),
	)
}

func LogInfo(source, activity, debugString string, object ...interface{}) {
	_, file, line, _ := runtime.Caller(1)
	caller := fmt.Sprintf("%s:%d", file, line)
	Logging.Info(debugString,
		zap.String("Source", source),
		zap.Any("Object", object),
		zap.String("Activity", activity),
		zap.String("Caller", caller),
	)
}

func LogWarning(source string, activity string, object interface{}, err ...error) {
	_, file, line, _ := runtime.Caller(1)
	caller := fmt.Sprintf("%s:%d", file, line)
	var errMsg string
	if len(err) > 0 {
		errMsg = err[0].Error()
	}
	Logging.Warn("Warning",
		zap.String("Source", source),
		zap.Any("Object", object),
		zap.String("Activity", activity),
		zap.String("Caller", caller),
		zap.String("Error", errMsg),
	)
}
