import argparse
import os
import zipfile
from dotenv import load_dotenv
from openai import AzureOpenAI

def genai(content, temp):
    client = AzureOpenAI(
        api_key = os.getenv('OPENAI_API_KEY'),
        api_version = "2023-10-01-preview",
        azure_endpoint = os.getenv('OPENAI_URL'),
        )
    response = client.chat.completions.create(
        model="gpt-3.5-turbo",
        # The prompt should enable AI to identify vulns in the code.
        messages=[{"role":"system","content":"You are an AI assistant that identifies code vulnerabilities"},                                   
                {"role":"user","content": content}],
                temperature=temp,
        )
    
    return response.choices[0].message.content

def read_zip_file(zip_file_path):
    # clean up files before scanning
    try:
        os.remove("sast.txt")
        os.remove("sca.txt")
    except Exception as e:
        # print(e)
        print("File not found, error ignored")

    with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
        # Get a list of all files in the zip archive
        file_list = zip_ref.namelist()

        # Read the content of each file in the zip archive
        for file_name in file_list:
            # print(file_name)
            with zip_ref.open(file_name) as file:
                if file_name.endswith('java'):
                    content = file.read()
                    # print(f"Content of {file_name}:\n{content.decode('utf-8')}")
                    # prompt generative AI for vulns in the code
                    vulns = genai("Find vulnerablities in the following code. Show the vulnerable line number. " + str(content.decode('utf-8')), temp=0.7)
                    # print("-" * 30 + " Vulns in file " + file_name)
                    filecontents = "\n" + "Vulns in file " + file_name + "-" * 30 + "\n" + vulns + "\n"
                    writetofile('sast.txt', filecontents, 'a')
                elif file_name.lower().endswith('pom.xml'):
                    content = file.read()

                    # to get vulnerable libraries, we need to generate dependency tree.
                    dep_tree = genai("generate dependency tree for " + content.decode('utf-8'), temp=0.1) # temp is 0.1 as we dont want to change the dependency tree often
                    # print('Dependency tree' + '-'*30)
                    # print(dep_tree)

                    # Using the dependency tree, generate vulnerable libraries
                    sca_vulns = genai("in the following dependency tree identify vulnerable libraries. Provide CVE number for each vulnerable library.  " + dep_tree, 0.1)

                    filecontents = "\n" + "Vulnerable libraries in " + file_name + "-" * 30 + "\n" + sca_vulns + "\n"
                    writetofile('sca.txt', filecontents, 'a')                    
                    # print(sca_vulns)

def writetofile(filename, content, mode='a'):
    with open(filename, mode) as file:
        file.write(content)

if __name__ == "__main__":
    # Load environment variables from .env
    load_dotenv()
    parser = argparse.ArgumentParser(description='Find SAST + SCA vulnerabilities in the zip archive.')
    parser.add_argument('zip_file', help='Path to the zip file.')

    args = parser.parse_args()

    read_zip_file(args.zip_file)
    print("Vulnerabilities (if any) list written to sast.txt and sca.txt files")
