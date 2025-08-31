 # PS5 FW 10.40 Toolbox

**PS5 Firmware 10.40 Toolbox**  
Scripts, analysis, and utilities for **reverse engineering the PS5 10.40 firmware**  
(binary dumps `.bin`, extraction, ROP gadgets, kernel offsets, etc.).


## Purpose
This repository provides **tools, scripts, and exports** for kernel exploitation and jailbreak development on PS5 Firmware 10.40.  
It focuses on automating tasks such as ROP gadget discovery, kernel offset validation, and vulnerability mapping to build and test reliable exploit chains.



## Contents
- **`ps5_fw1040_toolbox.csv`** → consolidated table of validated gadgets & kernel offsets  
- Python scripts to:
  - Scan extracted binary sections  
  - Identify useful ROP gadgets  
  - Verify kernel offsets  
  - Export results to structured logs & CSV files for further use  


## Installation

### 1. Clone the repository
```bash
git clone https://github.com/ericwot1/ps5-fw1040-toolbox.git
cd ps5-fw1040-toolbox
