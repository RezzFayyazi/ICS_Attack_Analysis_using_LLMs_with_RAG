import pandas as pd

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
    """
    Encode MITRE tactics into a binary format.
    """
    tactics_list = tactics.split(', ')
    return pd.Series([1 if tactic in tactics_list else 0 for tactic in mitre_tactics])

mitre_tactics = ['collection',
                'command and control',
                'credential access',
                'defense evasion',
                'discovery',
                'execution',
                'exfiltration',
                'impact',
                'initial access',
                'lateral movement',
                'persistence',
                'privilege escalation',
                'reconnaissance',
                'resource development']

try:
    df = pd.read_csv('./Results/MAIN_preds_gpt-3.5_rag_similar_procedure_urls.csv')
    x, indexes=count_tactics_in_csv("./Results/MAIN_preds_gpt-3.5_rag_similar_procedure_urls.csv", "source_documents")
    print(x)
    df2 = pd.read_csv('./Data/procedures_similarity_main.csv')
    filtered_df2 = df2.iloc[df2.index.isin(indexes)]

    # Count how many rows have 'matched' in the 'label' column
    matched_count = filtered_df2[filtered_df2['Label'] == 'not_matched'].shape[0]
    print(matched_count)
    matched_count2 = df2[df2['Label'] == 'not_matched'].shape[0]
    print(matched_count2)
    """
    df['mitre_tactics'] = df['result'].apply(find_mitre_tactics)

    encoded_df = df['mitre_tactics'].apply(encode_mitre_tactics)
    encoded_df.columns = mitre_tactics

    #df.to_csv('./preds_with_mitre_dataset_relationships.csv', index=False)
    encoded_df.to_csv('./Results/MAIN_preds_gpt-3.5_rag_similar_procedure_urls_encoded.csv', index=False)
    """
except Exception as e:
    print(f"An error occurred: {e}")

