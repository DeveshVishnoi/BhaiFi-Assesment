# BhaiFi Agent Service

## 🛠 Prerequisites

```bash
# Required Software
- Go 1.19+ (https://golang.org/dl/)
- WiX Toolset (https://wixtoolset.org/releases/)
- Windows OS (Tested on Windows 10/11)


## 🚀 Installation

### 1. Clone the Repository
```bash
git clone https://github.com/DeveshVishnoi/BhaiFi-Assesment.git
cd BhaiFi-Assesment

### 2. Build the Agent Service
```bash
cd Agent
go build cmd/server/main.go
# This will generate main.exe
```

### 3. Create MSI Installer
```bash
# Copy executable(main.exe) to installer directory
mv main.exe ../BhaiFI_Installer/

# Generate installer package
cd ../BhaiFI_Installer
candle.exe installer.wxs
light.exe installer.wixobj -o BhaiFi_Agent_Installer.msi
```

### 4. Install as Windows Service
```bash
msiexec /i "BhaiFi_Agent_Installer.msi" PORT="8080" TIME_INTERVAL="60"
```

### 5. API Usage
```bash
cd API_invoker
go build
./api_invoker.exe
```

### End Points

-`/api/scan/checkUnsigned` -- Scan for unsigned binaries

`/api/scan/checkMalicious` -- Detect malicious binaries(currently, random known binary hashes are used to simulate the detection process)

`/api/scan/checkRelationships` -- Check process relationships

### Configuration file available at this location

```bash
config/config.yaml
```

> **Note:**

- The agent binary runs as a **system service**.
- Please wait **1–2 minutes** after installation before invoking the APIs.
  - This delay is necessary because the agent takes some time to collect initial data and establish the gRPC connection.
  - If you invoke the API too early, you may receive `null` responses or experience connection errors.
- If you need to change any configuration:
  - Navigate to the `config/config.yaml` file.
  - Modify the desired settings.
  - Restart the agent binary for the changes to take effect.
