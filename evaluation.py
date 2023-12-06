import pandas as pd
from sklearn.metrics import classification_report, accuracy_score


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
    labels_df = pd.read_csv('./Data/ICS_Procedures_main_encoded.csv')
    labels = labels_df.values
    preds_df = pd.read_csv('./Results/preds_gpt-4-1106-preview_similar_procedure_urls_encoded.csv')
    preds = preds_df.values
    report, acc = eval(preds, labels)
    print(report)
    print(acc)
