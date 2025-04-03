# Use the official Ubuntu image as the base image
FROM kasmweb/desktop:1.16.0-rolling-daily

# Set environment variables to avoid interactive prompts during build
ENV DEBIAN_FRONTEND=noninteractive

# Install necessary packages for Xvfb and pyvirtualdisplay
USER root
RUN add-apt-repository -y ppa:deadsnakes/ppa && \
    apt-get update && \
    apt-get install -y python3.10 python3.10-venv python3.10-dev && \
    apt-get install -y \
        wget \
        gnupg \
        ca-certificates \
        libx11-xcb1 \
        libxcomposite1 \
        libxdamage1 \
        libxrandr2 \
        libxss1 \
        libxtst6 \
        libnss3 \
        libatk-bridge2.0-0 \
        libgtk-3-0 \
        x11-apps \
        fonts-liberation \
        libappindicator3-1 \
        libu2f-udev \
        libvulkan1 \
        libdrm2 \
        xdg-utils \
        xvfb \
        libasound2 \
        libcurl4 \
        libgbm1 \
        && rm -rf /var/lib/apt/lists/*

# Add Google Chrome repository and install Google Chrome
RUN wget https://mirror.cs.uchicago.edu/google-chrome/pool/main/g/google-chrome-stable/google-chrome-stable_126.0.6478.126-1_amd64.deb && \
    dpkg -i google-chrome-stable_126.0.6478.126-1_amd64.deb && \
    rm google-chrome-stable_126.0.6478.126-1_amd64.deb

# Install Python dependencies
RUN python3.10 -m pip install --upgrade pip

# Set up a working directory
WORKDIR /app

# Copy application files
COPY . .

# Install Python dependencies
RUN python3.10 -m pip install -e .

# Download wssocks and make it executable
RUN wget https://github.com/zetxtech/wssocks/releases/download/v1.4.2/wssocks-linux-amd64 -O /app/wssocks && \
    chmod +x /app/wssocks

# Expose the port for the FastAPI server
EXPOSE 3000

# Copy and set up startup script
COPY docker_startup.sh /
RUN chmod +x /docker_startup.sh

# Default command
ENTRYPOINT ["/docker_startup.sh"]
