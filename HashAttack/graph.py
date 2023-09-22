import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

# ==========================================================
# Calculate Theoretical Values
# ==========================================================
preimage = {}
collision = {}

for n_bits in range(8, 23, 2):
    preimage[n_bits] = 2 ** n_bits
    collision[n_bits] = 2 ** (n_bits / 2)

preimage_df = pd.DataFrame(list(preimage.items()), columns=['n_bits', 'preimage'])
collision_df = pd.DataFrame(list(collision.items()), columns=['n_bits', 'collision'])

print(preimage_df)
print(collision_df)

# ==========================================================
# Preimage
# ==========================================================

# Load the data from the CSV file into a Pandas DataFrame
df = pd.read_csv('preimage.csv')

fig, ax = plt.subplots(figsize=(10, 6))
ax.set_yscale("log")

# Create the box plot
boxprops = dict(linestyle='-', linewidth=1, color='black')
medianprops = dict(linestyle='-', linewidth=2.5, color='black')
whiskerprops = dict(linestyle='--', linewidth=1, color='gray')

boxplot = ax.boxplot(df.groupby('n_bits')['n_tries'].apply(list).values, 
                     positions=df['n_bits'].unique(), 
                     widths=0.6, 
                     showfliers=False,
                     patch_artist=True,
                     boxprops=boxprops,
                     medianprops=medianprops,
                     whiskerprops=whiskerprops)

# Plot the theoretical line
ax.plot(preimage_df['n_bits'], preimage_df['preimage'], marker='s', linestyle='-', markersize=6, color='black', label='Theoretical')

# Calculate and plot the average n_tries for each group of n_bits
average_tries = df.groupby('n_bits')['n_tries'].mean()
ax.scatter(average_tries.index, average_tries, color='cyan', marker='o', label='Average n_tries', zorder=3)  # Increase z-order to ensure visibility

# Optional: Add labels and a title
plt.xlabel("Number of Bits")
plt.ylabel("Number of Tries")
plt.title("Preimage Attack")

# Show the plot
plt.savefig('images/preimage.png')

# ==========================================================
# Collisions
# ==========================================================

# Load the data from the CSV file into a Pandas DataFrame
df = pd.read_csv('collision.csv')

# Create a box plot using Matplotlib
fig, ax = plt.subplots(figsize=(10, 6))
ax.set_yscale("log")

boxplot = ax.boxplot(df.groupby('n_bits')['n_tries'].apply(list).values, 
                     positions=df['n_bits'].unique(), 
                     widths=0.6, 
                     showfliers=False,
                     patch_artist=True,
                     boxprops=boxprops,
                     medianprops=medianprops,
                     whiskerprops=whiskerprops)

# Plot the theoretical line
ax.plot(collision_df['n_bits'], collision_df['collision'], marker='s', linestyle='-', markersize=6, color='black', label='Theoretical')

# Calculate and plot the average n_tries for each group of n_bits
average_tries = df.groupby('n_bits')['n_tries'].mean()
ax.scatter(average_tries.index, average_tries, color='cyan', marker='o', label='Average n_tries', zorder=3)  # Increase z-order to ensure visibility


# Set labels and title
plt.xlabel('Number of Bits')
plt.ylabel('Number of Tries')
plt.title('Collision Attack')

# Show the plot
plt.savefig('images/collision.png')

plt.show()
