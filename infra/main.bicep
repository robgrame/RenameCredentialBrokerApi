// Device Credential Broker — top-level deployment (docs/deployment.md, ADR 0001).
//
// Status: PROPOSED DESIGN. Provisions the hosting plan/app, Managed Identity, Application
// Insights, and VNet integration wiring described in docs/deployment.md. CyberArk-reachability
// resources (VPN/ExpressRoute/Private Link) are deliberately left as placeholders pending the
// open network decision (docs/network-connectivity.md, ADR 0004) — this template does not
// assume or fabricate on-prem connectivity details.
targetScope = 'resourceGroup'

@description('Short, lowercase, alphanumeric environment/app name used to build resource names.')
@minLength(3)
@maxLength(16)
param appName string = 'devcredbroker'

@description('Deployment environment suffix, e.g. dev, test, prod.')
param environmentName string = 'dev'

@description('Azure region for all resources.')
param location string = resourceGroup().location

@description('App Service plan SKU. Premium v3 recommended for VNet integration + client certs.')
param appServicePlanSku string = 'P1v3'

@description('Existing VNet resource ID to integrate the app with. Leave empty to skip VNet integration (not recommended for production — see docs/network-connectivity.md).')
param vnetIntegrationSubnetId string = ''

@description('Microsoft Graph application permissions the Managed Identity requires (documented, granted out-of-band by an Entra admin — see docs/device-validation.md).')
param requiredGraphApplicationPermissions array = [
  'Device.Read.All'
  'DeviceManagementManagedDevices.Read.All'
]

var resourceSuffix = '${appName}-${environmentName}'

module appInsights 'modules/app-insights.bicep' = {
  name: 'appInsights'
  params: {
    name: 'appi-${resourceSuffix}'
    location: location
  }
}

module appServicePlan 'modules/app-service-plan.bicep' = {
  name: 'appServicePlan'
  params: {
    name: 'plan-${resourceSuffix}'
    location: location
    sku: appServicePlanSku
  }
}

module appService 'modules/app-service.bicep' = {
  name: 'appService'
  params: {
    name: 'app-${resourceSuffix}'
    location: location
    appServicePlanId: appServicePlan.outputs.id
    appInsightsConnectionString: appInsights.outputs.connectionString
    vnetIntegrationSubnetId: vnetIntegrationSubnetId
  }
}

@description('Microsoft Graph application permissions that must be granted to the app Managed Identity out-of-band (documentation output only — this template does not grant permissions).')
output requiredGraphApplicationPermissions array = requiredGraphApplicationPermissions

output appServiceName string = appService.outputs.name
output appServiceDefaultHostName string = appService.outputs.defaultHostName
output appServicePrincipalId string = appService.outputs.principalId
