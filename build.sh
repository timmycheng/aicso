# AiCSO Docker Build Script
# Usage: ./build.sh (Linux/Mac) or build.bat (Windows)

echo "Building AiCSO Docker image..."
docker build -t aicso:0.1.0 .
echo "Build complete!"
echo ""
echo "Usage:"
echo "  docker run -it aicso:0.1.0 --help"
echo "  docker run -it aicso:0.1.0 init"
echo "  docker run -it aicso:0.1.0 case list"
echo ""
echo "With volume mount for persistent data:"
echo "  docker run -it -v aicso_data:/app/data -v ./config.yaml:/app/config.yaml aicso:0.1.0"
