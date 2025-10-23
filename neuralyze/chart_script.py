import plotly.graph_objects as go
from plotly.subplots import make_subplots

# Create a flowchart using plotly with improved layout and readability
fig = go.Figure()

# Define positions with better spacing
positions = {
    # Master key at top center
    'master_key': (5, 12),
    
    # Plaintext on left
    'plaintext': (0, 9),
    
    # Encryption Path A (left side) - more spaced out
    'iv1': (1, 8),
    'pad1': (1, 7),
    'aes1': (1, 6),
    'hmac1': (1, 5),
    'comb1': (1, 4),
    'b64_1': (1, 3),
    'enc1': (1, 1),
    
    # Encryption Path B (right side) - more spaced out
    'iv2': (9, 8),
    'pad2': (9, 7),
    'aes2': (9, 6),
    'hmac2': (9, 5),
    'comb2': (9, 4),
    'b64_2': (9, 3),
    'enc2': (9, 1),
    
    # Note box
    'note': (5, 0),
    
    # Decryption process (center-right) - better spaced
    'dec_input': (6, 1),
    'dec_b64': (6, 2),
    'dec_split': (6, 3),
    'dec_hmac': (6, 4),
    'dec_error': (8, 4),
    'dec_aes': (6, 5),
    'dec_pad': (6, 6),
    'dec_output': (6, 8)
}

# Define node data with better colors and contrast
nodes = {
    'master_key': {'text': '🔑 masterkee.k3y<br>64 bytes<br>[Encrypt 32B | MAC 32B]', 'color': '#2E8B57', 'textcolor': 'white', 'size': 60},
    'plaintext': {'text': '📄 dec_danielx.txt<br>20,480 bytes<br>OpenVPN Config', 'color': '#F5F5F5', 'textcolor': 'black', 'size': 55},
    
    # Encryption Path A - varied blue shades
    'iv1': {'text': 'Generate IV1<br>16 bytes', 'color': '#1FB8CD', 'textcolor': 'white', 'size': 45},
    'pad1': {'text': 'PKCS7 Padding<br>→20,496 bytes', 'color': '#5D878F', 'textcolor': 'white', 'size': 45},
    'aes1': {'text': 'AES-256-CBC<br>Encryption', 'color': '#1FB8CD', 'textcolor': 'white', 'size': 45},
    'hmac1': {'text': 'HMAC-SHA256<br>IV1+Cipher1', 'color': '#DB4545', 'textcolor': 'white', 'size': 45},
    'comb1': {'text': 'Combine<br>20,544 bytes', 'color': '#5D878F', 'textcolor': 'white', 'size': 45},
    'b64_1': {'text': 'Base64 Encode<br>27,392 chars', 'color': '#1FB8CD', 'textcolor': 'white', 'size': 45},
    'enc1': {'text': '💾 enc_danielx.enc<br>IV1|Cipher1|HMAC1', 'color': '#F5F5F5', 'textcolor': 'black', 'size': 55},
    
    # Encryption Path B - same varied colors
    'iv2': {'text': 'Generate IV2<br>16 bytes', 'color': '#1FB8CD', 'textcolor': 'white', 'size': 45},
    'pad2': {'text': 'PKCS7 Padding<br>→20,496 bytes', 'color': '#5D878F', 'textcolor': 'white', 'size': 45},
    'aes2': {'text': 'AES-256-CBC<br>Encryption', 'color': '#1FB8CD', 'textcolor': 'white', 'size': 45},
    'hmac2': {'text': 'HMAC-SHA256<br>IV2+Cipher2', 'color': '#DB4545', 'textcolor': 'white', 'size': 45},
    'comb2': {'text': 'Combine<br>20,544 bytes', 'color': '#5D878F', 'textcolor': 'white', 'size': 45},
    'b64_2': {'text': 'Base64 Encode<br>27,392 chars', 'color': '#1FB8CD', 'textcolor': 'white', 'size': 45},
    'enc2': {'text': '💾 dec2enc.enc<br>IV2|Cipher2|HMAC2', 'color': '#F5F5F5', 'textcolor': 'black', 'size': 55},
    
    # Note
    'note': {'text': '⚠️ Same plaintext + key<br>Different IV = Different output', 'color': '#D2BA4C', 'textcolor': 'black', 'size': 50},
    
    # Decryption - orange/yellow shades
    'dec_input': {'text': 'Input: .enc + key', 'color': '#D2BA4C', 'textcolor': 'black', 'size': 45},
    'dec_b64': {'text': 'Decode Base64', 'color': '#D2BA4C', 'textcolor': 'black', 'size': 45},
    'dec_split': {'text': 'Split Components', 'color': '#D2BA4C', 'textcolor': 'black', 'size': 45},
    'dec_hmac': {'text': 'Verify HMAC', 'color': '#DB4545', 'textcolor': 'white', 'size': 45},
    'dec_error': {'text': '❌ ERROR<br>Invalid HMAC', 'color': '#B4413C', 'textcolor': 'white', 'size': 40},
    'dec_aes': {'text': 'AES Decrypt', 'color': '#D2BA4C', 'textcolor': 'black', 'size': 45},
    'dec_pad': {'text': 'Remove Padding', 'color': '#D2BA4C', 'textcolor': 'black', 'size': 45},
    'dec_output': {'text': '📄 dec_danielx.txt<br>20,480 bytes', 'color': '#F5F5F5', 'textcolor': 'black', 'size': 55}
}

# Add nodes with improved styling
for node_id, pos in positions.items():
    node_info = nodes[node_id]
    fig.add_trace(go.Scatter(
        x=[pos[0]], y=[pos[1]],
        mode='markers+text',
        marker=dict(
            size=node_info['size'],
            color=node_info['color'],
            symbol='square',
            line=dict(width=2, color='#333333')
        ),
        text=node_info['text'],
        textposition='middle center',
        textfont=dict(size=12, color=node_info['textcolor']),
        showlegend=False,
        hoverinfo='none'
    ))

# Define connections with labels
connections = [
    # From plaintext to both encryption paths
    ('plaintext', 'iv1', ''),
    ('plaintext', 'iv2', ''),
    
    # Encryption Path A
    ('iv1', 'pad1', ''),
    ('pad1', 'aes1', ''),
    ('aes1', 'hmac1', ''),
    ('hmac1', 'comb1', ''),
    ('comb1', 'b64_1', ''),
    ('b64_1', 'enc1', ''),
    
    # Encryption Path B
    ('iv2', 'pad2', ''),
    ('pad2', 'aes2', ''),
    ('aes2', 'hmac2', ''),
    ('hmac2', 'comb2', ''),
    ('comb2', 'b64_2', ''),
    ('b64_2', 'enc2', ''),
    
    # To note
    ('enc1', 'note', ''),
    ('enc2', 'note', ''),
    
    # Decryption flow
    ('enc1', 'dec_input', ''),
    ('enc2', 'dec_input', ''),
    ('dec_input', 'dec_b64', ''),
    ('dec_b64', 'dec_split', ''),
    ('dec_split', 'dec_hmac', ''),
    ('dec_hmac', 'dec_error', 'Fail'),
    ('dec_hmac', 'dec_aes', 'Pass'),
    ('dec_aes', 'dec_pad', ''),
    ('dec_pad', 'dec_output', ''),
]

# Add arrows with better styling
for connection in connections:
    start, end = connection[0], connection[1]
    label = connection[2] if len(connection) > 2 else ''
    
    start_pos = positions[start]
    end_pos = positions[end]
    
    # Calculate arrow position
    mid_x = (start_pos[0] + end_pos[0]) / 2
    mid_y = (start_pos[1] + end_pos[1]) / 2
    
    fig.add_annotation(
        x=end_pos[0], y=end_pos[1],
        ax=start_pos[0], ay=start_pos[1],
        xref='x', yref='y',
        axref='x', ayref='y',
        arrowhead=2,
        arrowsize=1.5,
        arrowwidth=2,
        arrowcolor='#333333',
        showarrow=True
    )
    
    # Add label if exists
    if label:
        fig.add_trace(go.Scatter(
            x=[mid_x], y=[mid_y],
            mode='text',
            text=label,
            textfont=dict(size=10, color='#333333'),
            showlegend=False,
            hoverinfo='none'
        ))

# Add dashed lines from master key to crypto operations
master_connections = [
    ('master_key', 'aes1'), ('master_key', 'aes2'), 
    ('master_key', 'hmac1'), ('master_key', 'hmac2'),
    ('master_key', 'dec_hmac')
]

for start, end in master_connections:
    start_pos = positions[start]
    end_pos = positions[end]
    
    fig.add_shape(
        type="line",
        x0=start_pos[0], y0=start_pos[1],
        x1=end_pos[0], y1=end_pos[1],
        line=dict(color='#666666', width=2, dash='dash')
    )

# Update layout with better spacing
fig.update_layout(
    title="Encryption/Decryption Process",
    xaxis=dict(showgrid=False, zeroline=False, showticklabels=False, range=[-1, 11]),
    yaxis=dict(showgrid=False, zeroline=False, showticklabels=False, range=[-1, 13]),
    showlegend=False,
    plot_bgcolor='white',
    font=dict(size=12),
    autosize=True
)

# Save the chart
fig.write_image("encryption_decryption_flowchart.png")
fig.write_image("encryption_decryption_flowchart.svg", format="svg")

print("Improved flowchart created and saved successfully!")