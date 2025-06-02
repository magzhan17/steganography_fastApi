"# steganography_fastApi" 
# Docker needs to be installed!!!

# Build the Docker image
sudo docker build -t stego-app .

# Run the container
sudo docker run -d -p 8000:8000 --name stego-container stego-app

# In your browser open localhost:8000
