# ShadowPad Analysis Tools
[IDA Pro](https://www.hex-rays.com/products/ida/) scripts (IDAPython) whose goal is to help analysis of backdoor called ShadowPad, a.k.a. POISONPLUG. Main goal is to extract its configuration.
The scripts are confirmed on IDA Pro 7.5 SP2 + Python3, but I expect they work on 7.6 + Python3, too. 

In this repository, ShadowPad samples are categorized into the following types and the scripts are written for each type. 
- General
  - Other samples than "Code Scattering" below and mainly used until 2020
- Code Scattering
  - Instructions are scattered in the binary and this variant started to be used since 2020


