import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt

# ==========================================================
# Collisions
# ==========================================================

# Load the data from the CSV file into a Pandas DataFrame
data = pd.read_csv('collision.csv')

# Create a box plot using Seaborn
plt.figure(figsize=(10, 6))  # Optional: Set the figure size
sns.set(style="whitegrid")   # Optional: Set the style

# Create the box plot
ax1 = sns.boxplot(x="n_bits", y="n_tries", data=data)

# Optional: Add labels and a title
plt.xlabel("Number of Bits")
plt.ylabel("Number of Tries")
plt.title("Collision Attack")

# Set the y-axis to log scale
ax1.set_yscale("log")

# Show the plot
plt.show()

# ==========================================================
# Preimage
# ==========================================================

# Load the data from the CSV file into a Pandas DataFrame
data = pd.read_csv('preimage.csv')

# Create a box plot using Seaborn
plt.figure(figsize=(10, 6))  # Optional: Set the figure size
sns.set(style="whitegrid")   # Optional: Set the style

# Create the box plot
ax2 = sns.boxplot(x="n_bits", y="n_tries", data=data)

# Optional: Add labels and a title
plt.xlabel("Number of Bits")
plt.ylabel("Number of Tries")
plt.title("Preimage Attack")

# Set the y-axis to log scale
ax2.set_yscale("log")

# Show the plot
plt.show()
