@description('App Service plan name.')
param name string

@description('Azure region.')
param location string

@description('SKU name, e.g. P1v3. Premium v3 recommended for VNet integration (docs/deployment.md).')
param sku string = 'P1v3'

resource plan 'Microsoft.Web/serverfarms@2023-12-01' = {
  name: name
  location: location
  sku: {
    name: sku
  }
  kind: 'app'
  properties: {
    reserved: false
  }
}

output id string = plan.id
