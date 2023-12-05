import pandas as pd
from sklearn.metrics import classification_report, accuracy_score


def eval(preds, labels):
    mitre_tactics=['collection','command and control','credential access','defense evasion','discovery','execution','exfiltration','impact','initial access','lateral movement','persistence','privilege escalation','reconnaissance','resource development']
    report = classification_report(labels, preds,target_names=mitre_tactics)
    acc = accuracy_score(labels, preds)
    return report, acc

if __name__=="__main__":
    temp_arg = 0
    labels_df = pd.read_csv('./Data/procedures_labels_encoded.csv')
    labels = labels_df.values
    preds_df = pd.read_csv('./Results/MAIN_preds_gpt-3.5_rag_similar_procedure_urls_encoded.csv')
    preds = preds_df.values
    if temp_arg == 1:
        report, acc = eval(preds, labels)
        print(report)
        print(acc)
    elif temp_arg == 0:
        main_df = pd.read_csv('./Data/procedures_similarity_main.csv')
        matched_df = main_df[main_df['Label'] == 'not_matched']
        print(len(matched_df))
        matched_indexes = matched_df.index
        filtered_labels = labels[matched_indexes]
        filtered_preds = preds[matched_indexes]
        report, acc = eval(filtered_preds, filtered_labels)
        print(report)
        print(acc)
