import pandas as pd
import requests
from bs4 import BeautifulSoup

# Define the URL for the MITRE ATT&CK website
base_url = 'https://attack.mitre.org/'

# Define the DataFrame to store the content and labels
df = pd.DataFrame(columns=['URL', 'Tactic', 'Technique_ID', 'Technique', 'Procedure_ID', 'Procedure_Name', 'Description'])

visited_links = set()
sentences_set = set()



# Crawl MITRE techniques
technique_url = base_url + 'techniques/ics/'
technique_response = requests.get(technique_url)
technique_soup = BeautifulSoup(technique_response.content, 'html.parser')
techniques_enterprise = technique_soup.find('div', {'class':"tab-content col-xl-9 col-lg-9 col-md-8 pt-4"})
technique_links = techniques_enterprise.find_all('a')
for link in technique_links:
    technique_dict = dict()
    procedure_ids = []
    procedure_names = []
    procedure_descriptions = []
    technique_id = ''
    technique_name = link.text.strip()
    technique_url = base_url + link.get('href')
    
    if technique_url in visited_links:
        continue
    
    technique_response = requests.get(technique_url)
    technique_soup = BeautifulSoup(technique_response.content, 'html.parser')
    
    try:

        # get technique
        technique = technique_soup.find('h1')
        # get technique ID
        technique_id = technique_soup.find('span', {'class': 'h5 card-title'}).next_sibling.strip()
        tactic_card = technique_soup.find('div', {'id': 'card-tactics'})
        tactic_links = tactic_card.find_all('a')
        technique_names = [tactic_link.text for tactic_link in tactic_links]
        procedure_section = technique_soup.find('h2', text='Procedure Examples')
        if procedure_section:
            procedure_table = procedure_section.find_next('table', {'class': 'table table-bordered table-alternate mt-2'})
            procedure_rows = procedure_table.find_all('tr')
            
            for row in procedure_rows[1:]:  # Skip the header row
                columns = row.find_all('td')
                procedure_ids.append(columns[0].text.strip())
                procedure_names.append(columns[1].text.strip())
                procedure_descriptions.append(columns[2].text.strip())
            
            
        # Convert lists to strings
        procedure_ids_str = ', '.join(procedure_ids)
        procedure_names_str = ', '.join(procedure_names)
        procedure_descriptions_str = ', '.join(procedure_descriptions)
        # Create a new dictionary for each technique
        technique_dict = {
            'URL': technique_url,
            'Tactic': technique_names,
            'Technique_ID': technique_id,
            'Technique': technique.get_text(strip=True)
        }

        # Append technique_dict to the DataFrame for the main technique information
        df = pd.concat([df, pd.DataFrame([technique_dict])], ignore_index=True)

        # Append mitigation and detection information as separate rows
        for i in range(len(procedure_ids)):
            procedure_dict = {
                'Procedure_ID': procedure_ids[i],
                'Procedure_Name': procedure_names[i],
                'Description': procedure_descriptions[i]
            }
            df = pd.concat([df, pd.DataFrame([procedure_dict])], ignore_index=True)

        #df = df.append(technique_dict, ignore_index=True)
        visited_links.add(technique_url)

    except AttributeError:
        continue


print(df)
df.to_csv('C://Users//rf1679//Desktop//ICS_Procedures.csv', index=False)