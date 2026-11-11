resource "aws_s3_bucket" "data" {
  bucket = "example-data"
  acl    = "public-read"
}

resource "aws_security_group" "admin" {
  name = "admin"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
