
import { motion } from 'framer-motion';
import { Facebook, Twitter, Linkedin, Instagram, Mail, Phone, MapPin } from 'lucide-react';
import { Link } from 'react-router-dom';

function Footer() {
  const currentYear = new Date().getFullYear();

  const containerVariants = {
    hidden: { opacity: 0 },
    visible: {
      opacity: 1,
      transition: {
        staggerChildren: 0.1,
      },
    },
  };

  const itemVariants = {
    hidden: { y: 20, opacity: 0 },
    visible: {
      y: 0,
      opacity: 1,
    },
  };

  return (
    <footer className="bg-background border-t-2 pt-6">
      <motion.div
        className="container mx-auto px-4"
        variants={containerVariants}
        initial="hidden"
        animate="visible"
      >
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-12">
          <motion.div variants={itemVariants}>
            <h3 className="text-2xl font-bold mb-6">About Us</h3>
            <p className=" leading-relaxed">
              We are dedicated to providing up-to-date financial insights and resources to help you make better financial decisions.
            </p>
          </motion.div>

          <motion.div variants={itemVariants}>
            <h3 className="text-2xl font-bold  mb-6">Quick Links</h3>
            <ul className="space-y-2">
              <Link to={'/'}><li>Home</li></Link>
              <Link to={'/services'}><li>Services</li></Link>
              <Link to={'/contacts'}><li>Contacts</li></Link>
              
            </ul>
          </motion.div>

          <motion.div variants={itemVariants}>
            <h3 className="text-2xl font-bold  mb-6">Contact Us</h3>
            <ul className="space-y-4">
              <li className="flex items-center">
                <Mail className="mr-2 text-blue-400" size={18} />
                <span>TeenFinance@financewebsite.com</span>
              </li>
              <li className="flex items-center">
                <Phone className="mr-2 text-blue-400" size={18} />
                <span>+91 9380230469</span>
              </li>
              <li className="flex items-center">
                <MapPin className="mr-2 text-blue-400" size={18} />
                <span>Reva University, Bengaluru</span>
              </li>
            </ul>
          </motion.div>

          <motion.div variants={itemVariants}>
            <h3 className="text-2xl font-bold text-white mb-6">Follow Us</h3>
            <div className="flex space-x-4">
              {[
                { icon: Facebook, href: 'https://www.facebook.com' },
                { icon: Twitter, href: 'https://www.twitter.com' },
                { icon: Linkedin, href: 'https://www.linkedin.com' },
                { icon: Instagram, href: 'https://www.instagram.com/dev.track?igsh=MXQ4MGpoMmdzbjg1bw==' },
              ].map(({ icon: Icon, href }) => (
                <a
                  key={href}
                  href={href}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="hover:text-white transition-colors duration-300"
                >
                  <Icon size={24} />
                </a>
              ))}
            </div>
          </motion.div>
        </div>

        <motion.div
          className="text-center mt-12 pt-8 border-t border-gray-800 text-gray-400"
          variants={itemVariants}
        >
          <p>&copy; {currentYear} Finance Website. All Rights Reserved.</p>
        </motion.div>
      </motion.div>
    </footer>
  );
}

export default Footer;