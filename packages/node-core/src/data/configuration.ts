export interface DatabaseAdapter {
  checkReady(): Promise<void>;
}

export interface DatabaseConfiguration {
  readonly connectionString: string;
  readonly adapter: DatabaseAdapter;
}

export class DatabaseConfigurationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DatabaseConfigurationError";
  }
}

export function requireDatabaseAdapter(
  configuration: DatabaseConfiguration,
): DatabaseAdapter {
  if (configuration === undefined) {
    throw new DatabaseConfigurationError("database configuration is required");
  }
  if (
    configuration.connectionString === undefined ||
    configuration.connectionString.trim() === ""
  ) {
    throw new DatabaseConfigurationError("database connection string is required");
  }
  if (
    configuration.adapter === undefined ||
    typeof configuration.adapter.checkReady !== "function"
  ) {
    throw new DatabaseConfigurationError("database adapter is required");
  }
  return configuration.adapter;
}
