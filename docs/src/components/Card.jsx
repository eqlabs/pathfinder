import React from 'react';
import Link from '@docusaurus/Link';

const Card = ({ href, icon, title, description }) => {
  return (
    <Link className="docs-card-container" href={href}>
      <div className="docs-card">
        <div className="card-icon">{icon}</div>
        <div>
          <header className="card-header">{title}</header>
          <div className="card-content">
            <p>{description}</p>
          </div>
        </div>
      </div>
    </Link>
  );
};

export default Card;
