#!/bin/sh

# Start the Ollama server in the background
ollama serve &

# Wait for the server to be ready
until ollama list >/dev/null 2>&1; do
  sleep 1
done

# Pull the llama3 model (replace with the exact name if it's llama3:latest or llama3:instruct etc.)
echo "Pulling ollama model..."
ollama pull granite4:latest
ollama pull tev1:0.8b
ollama list
#ollama pull tinyllama
# Ollama pull a_model_of_your_choice

# Keep the server in the foreground (use PID of backgrounded server if needed)
wait

