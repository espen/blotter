# Build stage: compile native gems
FROM ruby:4.0.7-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential libsqlite3-dev libyaml-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY Gemfile Gemfile.lock ./
RUN bundle config set --local without test && bundle install --jobs 4

# Runtime stage (sqlite3 CLI included for online .backup from the host)
FROM ruby:4.0.7-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      libsqlite3-0 sqlite3 \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /usr/local/bundle /usr/local/bundle
COPY . .
ENV RACK_ENV=production BUNDLE_WITHOUT=test
EXPOSE 9292
CMD ["bundle", "exec", "puma", "-p", "9292"]
