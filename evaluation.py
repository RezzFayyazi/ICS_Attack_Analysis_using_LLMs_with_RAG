import pandas as pd
from sklearn.metrics import classification_report, accuracy_score
import argparse

parser = argparse.ArgumentParser(description="MITRE ICS Evaluation")
parser.add_argument('--encoded_file_path', type=str, default='./Results/preds_gpt-3.5-turbo-1106_all_urls_encoded.csv', help='Specify the path to the encoded file for evaluation')
args = parser.parse_args()

def eval(preds, labels):
    mitre_tactics=['collection',
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
    report = classification_report(labels, preds,target_names=mitre_tactics)
    acc = accuracy_score(labels, preds)
    return report, acc

if __name__=="__main__":
    # TO RUN: python evaluation.py --encoded_file_path ./Results/preds_gpt-3.5-turbo-1106_all_urls_encoded.csv
    labels_df = pd.read_csv('./Data/ICS_Procedures_main_encoded.csv')
    labels = labels_df.values
    preds_df = pd.read_csv(args.encoded_file_path)
    preds = preds_df.values
    report, acc = eval(preds, labels)
    print(report)
    print(acc)
