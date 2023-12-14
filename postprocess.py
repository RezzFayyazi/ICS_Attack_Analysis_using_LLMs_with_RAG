import pandas as pd
import argparse

parser = argparse.ArgumentParser(description="MITRE ICS PostProcessing")
parser.add_argument('--file_path', type=str, default='./Results/preds_gpt-3.5-turbo-1106_all_urls.csv', help='Specify the path to extract the tactics keywords and encode the file before evaluation')
args = parser.parse_args()

def find_mitre_tactics(text):
    text = text.lower()
    found_tactics = [tactic for tactic in mitre_tactics if tactic in text]
    return ', '.join(found_tactics) if found_tactics else 'none'

def count_tactics_in_csv(file_path, text_column):
    df = pd.read_csv(file_path)
    counter = df[text_column].str.contains("Tactic:|Tactics:", na=False).sum()
    no_tactics_indexes = df[df[text_column].str.contains("Tactic:|Tactics:", na=False)].index.tolist()
    return counter, no_tactics_indexes

def encode_mitre_tactics(tactics):
    tactics_list = tactics.split(', ')
    return pd.Series([1 if tactic in tactics_list else 0 for tactic in mitre_tactics])


if __name__ == '__main__':
    #TO RUN: python postprocess.py --file_path ./Results/preds_gpt-3.5-turbo-1106_all_urls.csv
    mitre_tactics = ['collection',
    'command and control',
    'discovery',
    'evasion',
    'execution',
    'impact',
    'impair process control',
    'inhibit response function',
    'initial access',
    'lateral movement',
    'persistence',
    'privilege escalation']


    df = pd.read_csv(args.file_path)
    df['mitre_tactics'] = df['result'].apply(find_mitre_tactics)

    encoded_df = df['mitre_tactics'].apply(encode_mitre_tactics)
    encoded_df.columns = mitre_tactics
    encoded_df.to_csv(args.file_path.rsplit('.csv', 1)[0] + '_encoded.csv', index=False)
    

