# Pticks

A simple C# console application for monitoring network packets in real time. This application captures packets on a specified network interface and displays relevant information, including MAC addresses, packet size, and elapsed time.

## Table of Contents

- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
- [Example Output](#example-output)
- [License](#license)

## Features

- Captures network packets from the first available network device.
- Displays a summary of packet information in a tabular format.
- Shows sender and receiver MAC addresses, data size, time elapsed, and any errors (if implemented).
- Real-time monitoring of network activity.

## Prerequisites

Before you begin, ensure you have the following installed:

- [.NET SDK](https://dotnet.microsoft.com/download) (version 5.0 or later)
- [Visual Studio](https://visualstudio.microsoft.com/) or any C# compatible IDE
- [Pcap.Net library](https://pcapdotnet.github.io/) for packet capturing

