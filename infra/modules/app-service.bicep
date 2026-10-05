@description('App Service (Web App) name.')
param name string

@description('Azure region.')
param location string

@description('Resource ID of the App Service plan.')
param appServicePlanId string

@description('Application Insights connection string.')
@secure()
param appInsightsConnectionString string

@description('Existing VNet subnet resource ID for regional VNet integration. Empty skips integration (docs/network-connectivity.md — open decision).')
param vnetIntegrationSubnetId string = ''

resource app 'Microsoft.Web/sites@2023-12-01' = {
  name: name
  location: location
  kind: 'app'
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    serverFarmId: appServicePlanId
    httpsOnly: true
    // VERIFIED REQUIREMENT (prompt §5, docs/authentication.md): mutual TLS is required for
    // every path, including health checks — no clientCertExclusionPaths, mirroring the
    // verified-safe LogCollector configuration (docs/deployment.md).
    clientCertEnabled: true
    clientCertMode: 'Required'
    virtualNetworkSubnetId: !empty(vnetIntegrationSubnetId) ? vnetIntegrationSubnetId : null
    siteConfig: {
      netFrameworkVersion: 'v10.0'
      minTlsVersion: '1.2'
      ftpsState: 'Disabled'
      alwaysOn: true
      healthCheckPath: '/healthz'
      appSettings: [
        {
          name: 'APPLICATIONINSIGHTS_CONNECTION_STRING'
          value: appInsightsConnectionString
        }
        {
          name: 'ASPNETCORE_ENVIRONMENT'
          value: 'Production'
        }
        {
          name: 'WEBSITE_VNET_ROUTE_ALL'
          value: !empty(vnetIntegrationSubnetId) ? '1' : '0'
        }
      ]
    }
  }
}

output id string = app.id
output name string = app.name
output defaultHostName string = app.properties.defaultHostName
output principalId string = app.identity.principalId
