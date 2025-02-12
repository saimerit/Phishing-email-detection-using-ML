import pandas as pd

# Step 1: Load the CSV file into a DataFrame
df = pd.read_csv("C:\\Users\\sobha\\Downloads\\messages.csv")

# Step 2: Modify the binary data in a specific column
# Assuming the binary data column is named "binary_column"
# For example, change 0 to 1 and 1 to 0 in the column
df['Email Type'] = df['Email Type'].apply(lambda x: 'Phishing Email' if x == 1 else 'Safe Email')

# Step 3: Save the modified DataFrame to a new CSV file
df.to_csv("updated_file.csv", index=False)