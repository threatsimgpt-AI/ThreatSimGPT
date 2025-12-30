#!/bin/bash
# PostgreSQL initialization script
# This script runs when the PostgreSQL container is first created

set -e

# Create extensions
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
    -- Enable UUID extension
    CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
    
    -- Enable pgcrypto for encryption functions
    CREATE EXTENSION IF NOT EXISTS "pgcrypto";
    
    -- Enable pg_trgm for text search
    CREATE EXTENSION IF NOT EXISTS "pg_trgm";
    
    -- Create schemas
    CREATE SCHEMA IF NOT EXISTS threatsimgpt;
    CREATE SCHEMA IF NOT EXISTS analytics;
    CREATE SCHEMA IF NOT EXISTS audit;
    
    -- Grant permissions
    GRANT ALL PRIVILEGES ON SCHEMA threatsimgpt TO $POSTGRES_USER;
    GRANT ALL PRIVILEGES ON SCHEMA analytics TO $POSTGRES_USER;
    GRANT ALL PRIVILEGES ON SCHEMA audit TO $POSTGRES_USER;
    
    -- Create audit table
    CREATE TABLE IF NOT EXISTS audit.activity_log (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        user_id VARCHAR(255),
        action VARCHAR(100) NOT NULL,
        resource_type VARCHAR(100),
        resource_id VARCHAR(255),
        details JSONB,
        ip_address INET,
        user_agent TEXT
    );
    
    -- Create index on timestamp for faster queries
    CREATE INDEX IF NOT EXISTS idx_activity_log_timestamp ON audit.activity_log(timestamp DESC);
    CREATE INDEX IF NOT EXISTS idx_activity_log_user_id ON audit.activity_log(user_id);
    CREATE INDEX IF NOT EXISTS idx_activity_log_action ON audit.activity_log(action);
    
    -- Create simulations table
    CREATE TABLE IF NOT EXISTS threatsimgpt.simulations (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        template_name VARCHAR(255) NOT NULL,
        provider VARCHAR(50) NOT NULL,
        model VARCHAR(100),
        status VARCHAR(50) DEFAULT 'pending',
        num_variations INTEGER DEFAULT 1,
        metadata JSONB,
        results JSONB,
        error_message TEXT
    );
    
    -- Create index for simulations
    CREATE INDEX IF NOT EXISTS idx_simulations_created_at ON threatsimgpt.simulations(created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_simulations_status ON threatsimgpt.simulations(status);
    CREATE INDEX IF NOT EXISTS idx_simulations_template ON threatsimgpt.simulations(template_name);
    
    -- Create generated content table
    CREATE TABLE IF NOT EXISTS threatsimgpt.generated_content (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        simulation_id UUID REFERENCES threatsimgpt.simulations(id) ON DELETE CASCADE,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        content_type VARCHAR(50) NOT NULL,
        subject TEXT,
        body TEXT,
        metadata JSONB,
        safety_score DECIMAL(3,2),
        quality_score DECIMAL(3,2)
    );
    
    -- Create index for generated content
    CREATE INDEX IF NOT EXISTS idx_generated_content_simulation ON threatsimgpt.generated_content(simulation_id);
    CREATE INDEX IF NOT EXISTS idx_generated_content_created_at ON threatsimgpt.generated_content(created_at DESC);
    
    -- Create analytics aggregation table
    CREATE TABLE IF NOT EXISTS analytics.daily_stats (
        date DATE PRIMARY KEY,
        total_simulations INTEGER DEFAULT 0,
        successful_simulations INTEGER DEFAULT 0,
        failed_simulations INTEGER DEFAULT 0,
        total_content_generated INTEGER DEFAULT 0,
        avg_generation_time_seconds DECIMAL(10,2),
        providers_used JSONB,
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
    );
    
    -- Create function to update timestamp
    CREATE OR REPLACE FUNCTION update_updated_at_column()
    RETURNS TRIGGER AS \$\$
    BEGIN
        NEW.updated_at = CURRENT_TIMESTAMP;
        RETURN NEW;
    END;
    \$\$ language 'plpgsql';
    
    -- Create trigger for simulations
    DROP TRIGGER IF EXISTS update_simulations_updated_at ON threatsimgpt.simulations;
    CREATE TRIGGER update_simulations_updated_at
        BEFORE UPDATE ON threatsimgpt.simulations
        FOR EACH ROW
        EXECUTE FUNCTION update_updated_at_column();
    
    -- Log initialization
    INSERT INTO audit.activity_log (action, resource_type, details)
    VALUES ('database_initialized', 'system', '{"message": "ThreatSimGPT database initialized successfully"}');
    
EOSQL

echo "ThreatSimGPT PostgreSQL database initialized successfully!"
