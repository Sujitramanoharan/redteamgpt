# RedTeamGPT production container
FROM python:3.11-slim

WORKDIR /app

# Install dependencies first (cached layer)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the whole project
COPY . .

# Build the dataset + train the detector at image-build time.
# HF_TOKEN is passed as a build argument (needed for the gated AdvBench dataset).
ARG HF_TOKEN
ENV HF_TOKEN=${HF_TOKEN}
RUN python src/data_prep.py && python src/train_detector.py

EXPOSE 7860

CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "7860"]
