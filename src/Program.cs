using AnomalyDetector;
using Serilog;

var builder = Host.CreateDefaultBuilder(args)
    .UseWindowsService(options =>
    {
        options.ServiceName = "AnomalyDetectorService";
    })
    .ConfigureServices((context, services) =>
    {
        Log.Logger = new LoggerConfiguration()
            .MinimumLevel.Information()
            .MinimumLevel.Override("Microsoft", Serilog.Events.LogEventLevel.Information)
            .WriteTo.File(
                path: @"C:\ProgramData\AnomalyDetector\service-.txt",
                rollingInterval: RollingInterval.Day,
                outputTemplate: "[{Timestamp:yyyy-MM-dd HH:mm:ss} {Level:u3}] {Message:lj}{NewLine}{Exception}"
            )
            .Enrich.FromLogContext()
            .CreateLogger();

        services.AddLogging(options =>
        {
            options.ClearProviders();
            options.AddSerilog(Log.Logger);
        });

        services.AddSingleton<PatternMatcher>();

        services.AddHostedService<Worker>();
    });

var host = builder.Build();
host.Run();
