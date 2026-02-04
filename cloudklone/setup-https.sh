#!/bin/bash

# CloudKlone HTTPS Setup Script
set -e

echo "🔒 CloudKlone HTTPS Setup"
echo "=========================="
echo ""
echo "Choose your HTTPS option:"
echo ""
echo "1) Self-Signed Certificate (Quick, homelab/dev)"
echo "   - No domain needed"
echo "   - Browser warnings (expected)"
echo "   - Works immediately"
echo ""
echo "2) Let's Encrypt + Traefik (Recommended for production)"
echo "   - Valid SSL certificate"
echo "   - Requires domain name"
echo "   - Automatic renewal"
echo ""
echo "3) Exit (configure manually)"
echo ""

read -p "Select option [1-3]: " option

case $option in
    1)
        echo ""
        echo "🟢 Setting up Self-Signed Certificate..."
        echo ""
        
        # Generate certificate
        ./generate-self-signed-cert.sh
        
        echo ""
        echo "✅ Certificate generated!"
        echo ""
        echo "⚠️  To complete setup:"
        echo "1. Add nginx to docker-compose.yml (see HTTPS-SETUP-GUIDE.md)"
        echo "2. Create nginx-https.conf (see guide)"
        echo "3. Run: sudo docker-compose up -d"
        echo ""
        echo "📖 Full guide: HTTPS-SETUP-GUIDE.md (Option 1)"
        ;;
        
    2)
        echo ""
        echo "🟦 Setting up Let's Encrypt + Traefik..."
        echo ""
        
        # Check if .env.https exists
        if [ ! -f .env.https ]; then
            cp .env.https.example .env.https
            echo "Created .env.https from template"
        fi
        
        echo ""
        echo "Please configure your domain settings:"
        echo ""
        read -p "Enter your domain name (e.g., cloudklone.yourdomain.com): " DOMAIN
        read -p "Enter your email for Let's Encrypt notifications: " EMAIL
        
        # Update .env.https
        sed -i "s/DOMAIN=.*/DOMAIN=$DOMAIN/" .env.https
        sed -i "s/ACME_EMAIL=.*/ACME_EMAIL=$EMAIL/" .env.https
        
        echo ""
        echo "✅ Configuration saved to .env.https"
        echo ""
        echo "⚠️  Before deploying:"
        echo "1. Ensure DNS points to this server:"
        echo "   A Record: $DOMAIN → YOUR_SERVER_IP"
        echo "2. Ensure ports 80 and 443 are open on firewall"
        echo "3. Verify: dig +short $DOMAIN"
        echo ""
        read -p "Ready to deploy? [y/N]: " deploy
        
        if [[ "$deploy" =~ ^[Yy]$ ]]; then
            echo ""
            echo "🚀 Deploying with HTTPS..."
            sudo docker-compose down
            sudo docker-compose -f docker-compose.https.yml --env-file .env.https up -d
            echo ""
            echo "✅ Deployed! Certificate generation in progress..."
            echo ""
            echo "Monitor progress:"
            echo "  sudo docker-compose -f docker-compose.https.yml logs -f traefik"
            echo ""
            echo "Once complete, access at: https://$DOMAIN"
        else
            echo ""
            echo "Configuration saved. Deploy later with:"
            echo "  sudo docker-compose -f docker-compose.https.yml --env-file .env.https up -d"
        fi
        ;;
        
    3)
        echo ""
        echo "📖 See HTTPS-SETUP-GUIDE.md for manual configuration"
        echo ""
        exit 0
        ;;
        
    *)
        echo "Invalid option"
        exit 1
        ;;
esac

echo ""
echo "🎉 Setup complete!"
