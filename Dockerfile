# Use an official Python runtime as the base image
FROM python:3.12-alpine

# Set the working directory in the container
WORKDIR /app

# Install dependencies
COPY . /app/
RUN pip install -r requirements.txt

# Expose the port your app will run on
EXPOSE 8000

# Set the default command to run the application
CMD ["python", "auth_demo_ui/manage.py", "runserver", "0.0.0.0:8000"]

