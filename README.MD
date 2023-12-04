# Generative AI-Powered SAST + SCA application

## Introduction

This application uses Azure OpenAI to scan code for SAST (Static Application Security Testing) and SCA (Software Composition Analysis) vulnerablities. For SCA vulns, the application generates dependency tree and submits it to Open AI to get vulnerable libraries. The application is console based application, that expects a zip file as input. The application writes both SCA and SAST vulnerablities to the same folder in text format. The application only scans *.java for SAST vulns and pom.xml for SCA vulns.

The application includes https://github.com/appsecco/dvja code for demo purposes.

## Usage

```command-line
python3 app.py path/to/zip/file.zip
```
*Output*
```output
Vulnerabilities (if any) list written to sast.txt and sca.txt files
```

## TODO

- Find vulnerablities across files (source and sink are in different files)
- Expand to include other languages such as C#, python, javascript, SQL etc.
- Format output. 
- Create GUI.
- Adjust temparature of generative AI to ensure the same scan results everytime.