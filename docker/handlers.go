package docker

import (
	"fmt"
	"net/http"
)

func jsonResponse(w http.ResponseWriter, statusCode int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Api-Version", apiVersion)
	w.Header().Set("Docker-Experimental", "false")
	w.Header().Set("Server", "Docker/"+serverVersion+" (linux)")
	w.WriteHeader(statusCode)
	fmt.Fprint(w, body)
}

func handlePing(w http.ResponseWriter, r *http.Request) {
	captureAndSave(r)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Api-Version", apiVersion)
	w.Header().Set("Server", "Docker/"+serverVersion+" (linux)")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "OK")
}

func handleVersion(w http.ResponseWriter, r *http.Request) {
	captureAndSave(r)
	jsonResponse(w, http.StatusOK, `{
  "Platform": {"Name": "Docker Engine - Community"},
  "Components": [
    {"Name": "Engine", "Version": "`+serverVersion+`", "Details": {"ApiVersion": "`+apiVersion+`", "Arch": "amd64", "BuildTime": "2023-12-04T09:45:33.000000000+00:00", "Experimental": "false", "GitCommit": "311b9ff", "GoVersion": "go1.20.11", "KernelVersion": "5.15.0-91-generic", "MinAPIVersion": "1.12", "Os": "linux"}}
  ],
  "Version": "`+serverVersion+`",
  "ApiVersion": "`+apiVersion+`",
  "MinAPIVersion": "1.12",
  "GitCommit": "311b9ff",
  "GoVersion": "go1.20.11",
  "Os": "linux",
  "Arch": "amd64",
  "KernelVersion": "5.15.0-91-generic",
  "BuildTime": "2023-12-04T09:45:33.000000000+00:00"
}`)
}

func handleInfo(w http.ResponseWriter, r *http.Request) {
	captureAndSave(r)
	jsonResponse(w, http.StatusOK, `{
  "ID": "7TRN:IPZB:QYBB:WPUM:DHAP:YCY3:J5LA:Q2YN:MWOM:TDSW:JNGH:DYRK",
  "Containers": 3,
  "ContainersRunning": 2,
  "ContainersPaused": 0,
  "ContainersStopped": 1,
  "Images": 12,
  "Driver": "overlay2",
  "MemoryLimit": true,
  "SwapLimit": true,
  "KernelMemory": true,
  "CpuCfsPeriod": true,
  "CpuCfsQuota": true,
  "CPUShares": true,
  "CPUSet": true,
  "IPv4Forwarding": true,
  "BridgeNfIptables": true,
  "BridgeNfIp6tables": true,
  "DockerRootDir": "/var/lib/docker",
  "HttpProxy": "",
  "HttpsProxy": "",
  "NoProxy": "",
  "Name": "ip-172-31-24-6",
  "Labels": [],
  "ExperimentalBuild": false,
  "ServerVersion": "`+serverVersion+`",
  "OperatingSystem": "Ubuntu 22.04.3 LTS",
  "OSType": "linux",
  "Architecture": "x86_64",
  "NCPU": 4,
  "MemTotal": 8367833088,
  "KernelVersion": "5.15.0-91-generic",
  "OSVersion": "22.04"
}`)
}

func handleContainerList(w http.ResponseWriter, r *http.Request) {
	captureAndSave(r)
	jsonResponse(w, http.StatusOK, `[
  {"Id": "b4a2c1d3e5f6","Names": ["/web-app"],"Image": "nginx:latest","State": "running","Status": "Up 3 days","Ports": [{"PrivatePort": 80, "PublicPort": 80, "Type": "tcp"}]},
  {"Id": "c5d3e2f1a4b6","Names": ["/redis-cache"],"Image": "redis:7-alpine","State": "running","Status": "Up 3 days","Ports": [{"PrivatePort": 6379, "Type": "tcp"}]}
]`)
}

func handleContainerCreate(w http.ResponseWriter, r *http.Request) {
	captureAndSave(r)
	jsonResponse(w, http.StatusCreated, `{"Id": "`+fakeContainerID+`", "Warnings": []}`)
}

func handleContainerStart(w http.ResponseWriter, r *http.Request) {
	captureAndSave(r)
	w.Header().Set("Server", "Docker/"+serverVersion+" (linux)")
	w.WriteHeader(http.StatusNoContent)
}

func handleContainerInspect(w http.ResponseWriter, r *http.Request) {
	captureAndSave(r)
	jsonResponse(w, http.StatusOK, `{
  "Id": "`+fakeContainerID+`",
  "Created": "2024-01-15T10:30:00.000000000Z",
  "State": {"Status": "running", "Running": true, "Pid": 12345, "StartedAt": "2024-01-15T10:30:01.000000000Z"},
  "Name": "/web-app",
  "Image": "sha256:a1b2c3d4e5f6",
  "Config": {"Image": "nginx:latest", "Hostname": "a1b2c3d4e5f6"}
}`)
}

func handleExecCreate(w http.ResponseWriter, r *http.Request) {
	captureAndSave(r)
	jsonResponse(w, http.StatusCreated, `{"Id": "`+fakeExecID+`"}`)
}

func handleExecStart(w http.ResponseWriter, r *http.Request) {
	captureAndSave(r)
	w.Header().Set("Content-Type", "application/vnd.docker.raw-stream")
	w.Header().Set("Server", "Docker/"+serverVersion+" (linux)")
	w.WriteHeader(http.StatusOK)
}

func handleImageList(w http.ResponseWriter, r *http.Request) {
	captureAndSave(r)
	jsonResponse(w, http.StatusOK, `[
  {"Id": "sha256:a1b2c3d4e5f6", "RepoTags": ["nginx:latest"], "Size": 187000000, "Created": 1705312200},
  {"Id": "sha256:b2c3d4e5f6a1", "RepoTags": ["redis:7-alpine"], "Size": 32000000, "Created": 1705225800},
  {"Id": "sha256:c3d4e5f6a1b2", "RepoTags": ["ubuntu:22.04"], "Size": 77000000, "Created": 1705139400}
]`)
}

func handleImageCreate(w http.ResponseWriter, r *http.Request) {
	captureAndSave(r)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Server", "Docker/"+serverVersion+" (linux)")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `{"status":"Pulling from library/alpine","id":"latest"}
{"status":"Digest: sha256:c5b1261d6d3e43071626931fc004f70149baeba2c8ec672bd4f27761f8e1ad6b"}
{"status":"Status: Downloaded newer image for alpine:latest"}
`)
}

func handleCatchAll(w http.ResponseWriter, r *http.Request) {
	captureAndSave(r)
	jsonResponse(w, http.StatusNotFound, `{"message": "page not found"}`)
}
